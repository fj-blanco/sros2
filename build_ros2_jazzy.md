# ROS2 Jazzy Jalisco Installation Instructions

This guide provides instructions for installing ROS2 Jazzy Jalisco using two methods:

1. From binary packages on Ubuntu 24.04 (Noble)
2. From source on Ubuntu 22.04 (Jammy)

## Method 1: Installing ROS2 Jazzy Jalisco from Binary Packages (Ubuntu 24.04)

### Set up repositories

```bash
sudo apt install software-properties-common
sudo add-apt-repository universe

sudo apt update && sudo apt install curl -y
sudo curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key -o /usr/share/keyrings/ros-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] http://packages.ros.org/ros2/ubuntu $(. /etc/os-release && echo $UBUNTU_CODENAME) main" | sudo tee /etc/apt/sources.list.d/ros2.list > /dev/null
```

### Install ROS2 packages

```bash
sudo apt update
sudo apt install ros-jazzy-ros-base
```

### Install development tools (optional)

```bash
sudo apt install ros-dev-tools
```

### Install ROS2 demos

```bash
sudo apt install ros-jazzy-demo-nodes-cpp ros-jazzy-demo-nodes-py -y
```

### Set up environment

```bash
source /opt/ros/jazzy/setup.bash
```

## Method 2: Installing ROS2 Jazzy Jalisco from Source (Ubuntu 22.04)

### Install dependencies

```bash
sudo apt update && sudo apt install -y \
  python3-flake8-blind-except python3-flake8-class-newline python3-flake8-deprecated \
  python3-mypy python3-pip python3-pytest python3-pytest-cov python3-pytest-mock \
  python3-pytest-repeat python3-pytest-rerunfailures python3-pytest-runner \
  python3-pytest-timeout ros-dev-tools

sudo apt install -y \
  libasio-dev libx11-dev libxrandr-dev python3-empy liblttng-ust-dev lttng-tools \
  libbabeltrace-dev libxml2-dev pkg-config python3-lttng libglfw3-dev libglew-dev \
  libglm-dev libfreetype6-dev libpng-dev libjpeg-dev libqt5svg5-dev libqt5x11extras5-dev \
  qtbase5-dev qtdeclarative5-dev qtbase5-dev-tools
```

### Get ROS2 code

```bash
mkdir -p ~/ros2_jazzy/src
cd ~/ros2_jazzy
vcs import --input https://raw.githubusercontent.com/ros2/ros2/jazzy/ros2.repos src
```

### Install dependencies using rosdep

```bash
sudo rosdep init
rosdep update
rosdep install --from-paths src --ignore-src -y --skip-keys "fastcdr rti-connext-dds-6.0.1 urdfdom_headers"
```

### Build ROS2

```bash
cd ~/ros2_jazzy
colcon build --symlink-install
```

### Set up environment

```bash
source ~/ros2_jazzy/install/setup.bash
```

## Testing the Installation

To test your ROS2 installation, open two terminal windows:

Terminal 1 (C++ Talker):

```bash
source /opt/ros/jazzy/setup.bash  # For binary install
# OR
source ~/ros2_jazzy/install/setup.bash  # For source install
ros2 run demo_nodes_cpp talker
```

Terminal 2 (Python Listener):

```bash
source /opt/ros/jazzy/setup.bash  # For binary install
# OR
source ~/ros2_jazzy/install/setup.bash  # For source install
ros2 run demo_nodes_py listener
```

If the installation was successful, you should see the talker publishing messages and the listener receiving them.